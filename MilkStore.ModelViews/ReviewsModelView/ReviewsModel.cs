using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ReviewsModelView
{
    public class ReviewsModel
    {        
        public required string OrderDetailID { get; set; }
        //public required string ProductsID { get; set; }
        //public required string OrderID { get; set; }
        [Required(ErrorMessage = "Rating không được để trống")]
        [Range(1, 5, ErrorMessage = "Đánh giá từ 1 đến 5 sao")]
        public required int Rating { get; set; }
        [Required(ErrorMessage = "Comment không được để trống")]
        public required string Comment { get; set; }
    }
}
