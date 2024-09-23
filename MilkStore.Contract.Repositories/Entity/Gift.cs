using MilkStore.Core.Base;
using System.ComponentModel.DataAnnotations.Schema;

namespace MilkStore.Contract.Repositories.Entity
{
    public class Gift : BaseEntity
    {
        public int point { get; set; }
        public string GiftName { get; set; }

        [ForeignKey("ProductId")]
        public virtual Products Products { get; set; }
    }
}
