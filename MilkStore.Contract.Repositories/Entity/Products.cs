using MilkStore.Core.Base;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Products : BaseEntity
    {
        public string ProductName { get; set; }
        public double Price { get; set; }
        public string Description { get; set; }
        public int QuantityInStock { get; set; }
        public string ImageUrl { get; set; }

        //Thêm khóa ngoại
        public  string CategoryId { get; set; }
        [ForeignKey("CategoryId")]
        public virtual Category Category { get; set; }


        public virtual ICollection<PostProduct> PostProducts { get; set; } = new List<PostProduct>();
        public virtual ICollection<OrderDetails> OrderDetail { get; set; }

    }
}